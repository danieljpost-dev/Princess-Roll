//! WebGL2 renderer for the d20.
//!
//! The mesh is generated rather than loaded: twelve vertices from the golden
//! ratio, twenty faces, each split into its own three vertices so the shading
//! stays flat and every face gets clean texture coordinates. The numbers are
//! drawn into a canvas at startup and uploaded as one atlas, so there are no
//! asset files to ship and nothing to fetch.

use crate::dice::{Geometry, Quat, Vec3};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{
    CanvasRenderingContext2d, HtmlCanvasElement, WebGl2RenderingContext as Gl, WebGlProgram,
    WebGlTexture, WebGlUniformLocation,
};

const ATLAS_COLS: u32 = 5;
const ATLAS_ROWS: u32 = 4;
const CELL: u32 = 256;

const VERTEX_SHADER: &str = r#"#version 300 es
precision highp float;

layout(location = 0) in vec3 a_position;
layout(location = 1) in vec3 a_normal;
layout(location = 2) in vec2 a_uv;

uniform mat4 u_model;
uniform mat4 u_projection;

out vec3 v_normal;
out vec3 v_view;
out vec2 v_uv;

void main() {
    vec4 world = u_model * vec4(a_position, 1.0);
    v_normal = mat3(u_model) * a_normal;
    v_view = -world.xyz;
    v_uv = a_uv;
    gl_Position = u_projection * world;
}
"#;

const FRAGMENT_SHADER: &str = r#"#version 300 es
precision highp float;

in vec3 v_normal;
in vec3 v_view;
in vec2 v_uv;

uniform sampler2D u_numbers;
uniform vec3 u_body;
uniform vec3 u_ink;
uniform vec3 u_emissive;
uniform float u_emissive_amount;

out vec4 frag_colour;

void main() {
    vec3 normal = normalize(v_normal);
    vec3 view = normalize(v_view);

    // A warm key from the upper left and a cool fill from below right, so the
    // faces separate as the die turns.
    vec3 key_dir = normalize(vec3(-0.45, 0.8, 0.6));
    vec3 fill_dir = normalize(vec3(0.7, -0.4, 0.35));

    float key = max(dot(normal, key_dir), 0.0);
    float fill = max(dot(normal, fill_dir), 0.0) * 0.32;

    vec3 halfway = normalize(key_dir + view);
    float specular = pow(max(dot(normal, halfway), 0.0), 48.0) * 0.5;

    // Rim light keeps the silhouette readable against a dark background.
    float rim = pow(1.0 - max(dot(normal, view), 0.0), 3.0) * 0.45;

    vec3 base = u_body * (0.22 + key * 0.85 + fill) + vec3(specular) + u_body * rim * 2.2;

    // The atlas carries only the glyph in its alpha channel.
    float glyph = texture(u_numbers, v_uv).a;
    vec3 lit_ink = u_ink * (0.55 + key * 0.6) + vec3(specular * 0.6);
    vec3 colour = mix(base, lit_ink, glyph);

    colour = mix(colour, u_emissive, u_emissive_amount);
    frag_colour = vec4(colour, 1.0);
}
"#;

pub struct Highlight {
    pub colour: Vec3,
    pub amount: f32,
}

impl Highlight {
    pub const NONE: Highlight = Highlight {
        colour: Vec3::new(0.0, 0.0, 0.0),
        amount: 0.0,
    };
}

pub struct Renderer {
    gl: Gl,
    canvas: HtmlCanvasElement,
    program: WebGlProgram,
    vertex_count: i32,
    uniforms: Uniforms,
    body: Vec3,
    ink: Vec3,
}

struct Uniforms {
    model: WebGlUniformLocation,
    projection: WebGlUniformLocation,
    numbers: WebGlUniformLocation,
    body: WebGlUniformLocation,
    ink: WebGlUniformLocation,
    emissive: WebGlUniformLocation,
    emissive_amount: WebGlUniformLocation,
}

impl Renderer {
    pub fn new(canvas: HtmlCanvasElement, geometry: &Geometry) -> Result<Renderer, JsValue> {
        let gl = canvas
            .get_context("webgl2")?
            .ok_or_else(|| JsValue::from_str("this browser has no WebGL2"))?
            .dyn_into::<Gl>()?;

        let program = link_program(&gl, VERTEX_SHADER, FRAGMENT_SHADER)?;
        gl.use_program(Some(&program));

        let uniform = |name: &str| -> Result<WebGlUniformLocation, JsValue> {
            gl.get_uniform_location(&program, name)
                .ok_or_else(|| JsValue::from_str(&format!("shader is missing uniform {name}")))
        };
        let uniforms = Uniforms {
            model: uniform("u_model")?,
            projection: uniform("u_projection")?,
            numbers: uniform("u_numbers")?,
            body: uniform("u_body")?,
            ink: uniform("u_ink")?,
            emissive: uniform("u_emissive")?,
            emissive_amount: uniform("u_emissive_amount")?,
        };

        let (positions, normals, uvs) = build_mesh(geometry);
        let vertex_count = (positions.len() / 3) as i32;

        let vao = gl
            .create_vertex_array()
            .ok_or_else(|| JsValue::from_str("could not create a vertex array"))?;
        gl.bind_vertex_array(Some(&vao));
        upload_attribute(&gl, 0, &positions, 3)?;
        upload_attribute(&gl, 1, &normals, 3)?;
        upload_attribute(&gl, 2, &uvs, 2)?;

        let texture = build_number_atlas(&gl, geometry)?;
        gl.active_texture(Gl::TEXTURE0);
        gl.bind_texture(Gl::TEXTURE_2D, Some(&texture));
        gl.uniform1i(Some(&uniforms.numbers), 0);

        gl.enable(Gl::DEPTH_TEST);
        gl.enable(Gl::CULL_FACE);
        gl.cull_face(Gl::BACK);
        gl.clear_color(0.0, 0.0, 0.0, 0.0);

        Ok(Renderer {
            gl,
            canvas,
            program,
            vertex_count,
            uniforms,
            body: Vec3::new(0.38, 0.16, 0.52),
            ink: Vec3::new(1.0, 0.86, 0.94),
        })
    }

    /// Match the drawing buffer to the element's CSS size times the device
    /// pixel ratio, so the die is not soft on a phone or a retina display.
    pub fn resize(&self, device_pixel_ratio: f64) {
        let width = (self.canvas.client_width() as f64 * device_pixel_ratio).round() as u32;
        let height = (self.canvas.client_height() as f64 * device_pixel_ratio).round() as u32;

        if 0 == width || 0 == height {
            return;
        }
        if width != self.canvas.width() || height != self.canvas.height() {
            self.canvas.set_width(width);
            self.canvas.set_height(height);
        }
        self.gl.viewport(0, 0, width as i32, height as i32);
    }

    pub fn draw(&self, orientation: Quat, lift: f32, highlight: &Highlight) {
        let gl = &self.gl;
        gl.use_program(Some(&self.program));
        gl.clear(Gl::COLOR_BUFFER_BIT | Gl::DEPTH_BUFFER_BIT);

        let width = self.canvas.width().max(1) as f32;
        let height = self.canvas.height().max(1) as f32;
        let projection = perspective(0.85, width / height, 0.1, 100.0);
        let model = model_matrix(orientation, Vec3::new(0.0, lift, -3.6));

        gl.uniform_matrix4fv_with_f32_array(Some(&self.uniforms.projection), false, &projection);
        gl.uniform_matrix4fv_with_f32_array(Some(&self.uniforms.model), false, &model);
        gl.uniform3f(Some(&self.uniforms.body), self.body.x, self.body.y, self.body.z);
        gl.uniform3f(Some(&self.uniforms.ink), self.ink.x, self.ink.y, self.ink.z);
        gl.uniform3f(
            Some(&self.uniforms.emissive),
            highlight.colour.x,
            highlight.colour.y,
            highlight.colour.z,
        );
        gl.uniform1f(Some(&self.uniforms.emissive_amount), highlight.amount);

        gl.draw_arrays(Gl::TRIANGLES, 0, self.vertex_count);
    }
}

fn upload_attribute(gl: &Gl, location: u32, data: &[f32], size: i32) -> Result<(), JsValue> {
    let buffer = gl
        .create_buffer()
        .ok_or_else(|| JsValue::from_str("could not create a buffer"))?;
    gl.bind_buffer(Gl::ARRAY_BUFFER, Some(&buffer));

    // The view borrows the Rust slice directly; it must not outlive this call,
    // and nothing here allocates in between.
    unsafe {
        let view = js_sys::Float32Array::view(data);
        gl.buffer_data_with_array_buffer_view(Gl::ARRAY_BUFFER, &view, Gl::STATIC_DRAW);
    }

    gl.enable_vertex_attrib_array(location);
    gl.vertex_attrib_pointer_with_i32(location, size, Gl::FLOAT, false, 0, 0);
    Ok(())
}

/// One vertex per face corner: flat normals, and texture coordinates that put
/// each face in its own cell of the atlas.
fn build_mesh(geometry: &Geometry) -> (Vec<f32>, Vec<f32>, Vec<f32>) {
    let mut positions = Vec::with_capacity(20 * 9);
    let mut normals = Vec::with_capacity(20 * 9);
    let mut uvs = Vec::with_capacity(20 * 6);

    for face in 0..20 {
        let normal = geometry.face_normal(face);
        let cell = face as u32;
        let col = cell % ATLAS_COLS;
        let row = cell / ATLAS_COLS;

        for (corner, vertex_index) in geometry.faces()[face].iter().enumerate() {
            let position = geometry.vertex(*vertex_index);
            positions.extend_from_slice(&[position.x, position.y, position.z]);
            normals.extend_from_slice(&[normal.x, normal.y, normal.z]);

            // Derived from the face's tangent frame, so handedness is correct
            // no matter which way round the face table wound this triangle.
            let (local_u, local_v) = geometry.face_corner_uv(face, corner);
            uvs.push((col as f32 + local_u) / ATLAS_COLS as f32);
            // The atlas is uploaded flipped, so the top of the canvas is v = 1.
            uvs.push(1.0 - (row as f32 + (1.0 - local_v)) / ATLAS_ROWS as f32);
        }
    }

    (positions, normals, uvs)
}

/// Draw every face's number once into an offscreen canvas and hand it to the
/// GPU. Only the alpha channel is used; the shader supplies the colour.
fn build_number_atlas(gl: &Gl, geometry: &Geometry) -> Result<WebGlTexture, JsValue> {
    let document = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .document()
        .ok_or_else(|| JsValue::from_str("no document"))?;

    let canvas: HtmlCanvasElement = document.create_element("canvas")?.dyn_into()?;
    canvas.set_width(ATLAS_COLS * CELL);
    canvas.set_height(ATLAS_ROWS * CELL);

    let ctx: CanvasRenderingContext2d = canvas
        .get_context("2d")?
        .ok_or_else(|| JsValue::from_str("no 2d context for the number atlas"))?
        .dyn_into()?;

    ctx.set_text_align("center");
    ctx.set_text_baseline("middle");
    ctx.set_fill_style_str("#ffffff");

    for face in 0..20 {
        let number = geometry.number(face);
        let col = (face as u32) % ATLAS_COLS;
        let row = (face as u32) / ATLAS_COLS;
        let centre_x = (col * CELL) as f64 + CELL as f64 * 0.5;
        // The cell's centre is the face's centroid. Sitting a hair below it
        // buys a little more width, since the triangle widens toward its base.
        let centre_y = (row * CELL) as f64 + CELL as f64 * 0.54;

        let size = if number >= 10 { 86.0 } else { 104.0 };
        ctx.set_font(&format!("700 {size}px system-ui, -apple-system, sans-serif"));
        ctx.fill_text(&number.to_string(), centre_x, centre_y)?;

        // Underline 6 and 9 the way real dice do, so they cannot be confused.
        if 6 == number || 9 == number {
            let half = size * 0.30;
            let y = centre_y + size * 0.42;
            ctx.set_line_width(size * 0.08);
            ctx.set_stroke_style_str("#ffffff");
            ctx.begin_path();
            ctx.move_to(centre_x - half, y);
            ctx.line_to(centre_x + half, y);
            ctx.stroke();
        }
    }

    let texture = gl
        .create_texture()
        .ok_or_else(|| JsValue::from_str("could not create a texture"))?;
    gl.bind_texture(Gl::TEXTURE_2D, Some(&texture));
    // Without this the canvas's first row lands at v = 0 and the whole atlas
    // arrives upside down.
    gl.pixel_storei(Gl::UNPACK_FLIP_Y_WEBGL, 1);
    gl.tex_image_2d_with_u32_and_u32_and_html_canvas_element(
        Gl::TEXTURE_2D,
        0,
        Gl::RGBA as i32,
        Gl::RGBA,
        Gl::UNSIGNED_BYTE,
        &canvas,
    )?;
    gl.generate_mipmap(Gl::TEXTURE_2D);
    gl.tex_parameteri(
        Gl::TEXTURE_2D,
        Gl::TEXTURE_MIN_FILTER,
        Gl::LINEAR_MIPMAP_LINEAR as i32,
    );
    gl.tex_parameteri(Gl::TEXTURE_2D, Gl::TEXTURE_MAG_FILTER, Gl::LINEAR as i32);
    gl.tex_parameteri(Gl::TEXTURE_2D, Gl::TEXTURE_WRAP_S, Gl::CLAMP_TO_EDGE as i32);
    gl.tex_parameteri(Gl::TEXTURE_2D, Gl::TEXTURE_WRAP_T, Gl::CLAMP_TO_EDGE as i32);

    Ok(texture)
}

fn compile_shader(gl: &Gl, kind: u32, source: &str) -> Result<web_sys::WebGlShader, JsValue> {
    let shader = gl
        .create_shader(kind)
        .ok_or_else(|| JsValue::from_str("could not create a shader"))?;
    gl.shader_source(&shader, source);
    gl.compile_shader(&shader);

    if gl
        .get_shader_parameter(&shader, Gl::COMPILE_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        Ok(shader)
    } else {
        Err(JsValue::from_str(&
            gl.get_shader_info_log(&shader)
                .unwrap_or_else(|| "shader failed to compile".into()),
        ))
    }
}

fn link_program(gl: &Gl, vertex: &str, fragment: &str) -> Result<WebGlProgram, JsValue> {
    let program = gl
        .create_program()
        .ok_or_else(|| JsValue::from_str("could not create a program"))?;
    gl.attach_shader(&program, &compile_shader(gl, Gl::VERTEX_SHADER, vertex)?);
    gl.attach_shader(&program, &compile_shader(gl, Gl::FRAGMENT_SHADER, fragment)?);
    gl.link_program(&program);

    if gl
        .get_program_parameter(&program, Gl::LINK_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        Ok(program)
    } else {
        Err(JsValue::from_str(&
            gl.get_program_info_log(&program)
                .unwrap_or_else(|| "program failed to link".into()),
        ))
    }
}

/// Column-major, as GL expects.
fn perspective(fov_y: f32, aspect: f32, near: f32, far: f32) -> [f32; 16] {
    let f = 1.0 / (fov_y * 0.5).tan();
    let range = 1.0 / (near - far);
    [
        f / aspect, 0.0, 0.0, 0.0,
        0.0, f, 0.0, 0.0,
        0.0, 0.0, (near + far) * range, -1.0,
        0.0, 0.0, near * far * range * 2.0, 0.0,
    ]
}

fn model_matrix(q: Quat, translation: Vec3) -> [f32; 16] {
    let Quat { w, x, y, z } = q.normalized();
    let (xx, yy, zz) = (x * x, y * y, z * z);
    let (xy, xz, yz) = (x * y, x * z, y * z);
    let (wx, wy, wz) = (w * x, w * y, w * z);

    [
        1.0 - 2.0 * (yy + zz), 2.0 * (xy + wz), 2.0 * (xz - wy), 0.0,
        2.0 * (xy - wz), 1.0 - 2.0 * (xx + zz), 2.0 * (yz + wx), 0.0,
        2.0 * (xz + wy), 2.0 * (yz - wx), 1.0 - 2.0 * (xx + yy), 0.0,
        translation.x, translation.y, translation.z, 1.0,
    ]
}
